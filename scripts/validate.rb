#!/usr/bin/env ruby
# frozen_string_literal: true

require 'cgi'
require 'json'
require 'uri'

module PublicRepo
  module Validator
    SCHEMA_VERSION = 1
    SITE_FIELDS = %w[name url description tags].freeze
    START_MARKER = '<!-- AUTO-GENERATED-CONTENT:START -->'
    END_MARKER = '<!-- AUTO-GENERATED-CONTENT:END -->'
    FORBIDDEN_FIELDS = %w[
      id status hidden offline_reason deleted_at prev_title prev_description
      prev_keywords qrcode logo screenshot created_at updated_at
    ].freeze
    SENSITIVE_QUERY_KEYS = %w[
      accesstoken apikey auth authorization clientsecret code credential credentials
      invite invitation jwt key password referral secret session sessionid sharetoken
      signature token
    ].freeze
    SECRET_PATTERNS = [
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
      /\bAKIA[0-9A-Z]{16}\b/,
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
      /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
      /\bsk-[A-Za-z0-9_-]{20,}\b/,
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/
    ].freeze

    module_function

    def validate_repository!(root)
      readme_path = File.join(root, 'README.md')
      data_path = File.join(root, 'data', 'navigation.json')
      raise ArgumentError, 'README.md 不存在' unless File.file?(readme_path)
      raise ArgumentError, 'data/navigation.json 不存在' unless File.file?(data_path)
      raise ArgumentError, '不允许生成 data/stats.json' if File.exist?(File.join(root, 'data', 'stats.json'))

      readme = File.read(readme_path, encoding: 'UTF-8')
      catalog = JSON.parse(File.read(data_path, encoding: 'UTF-8'))
      validate_catalog!(catalog, readme)
      true
    rescue JSON::ParserError => error
      raise ArgumentError, "navigation.json 不是有效 JSON: #{error.message}"
    end

    def validate_catalog!(catalog, readme)
      raise ArgumentError, 'schema_version 不受支持' unless catalog['schema_version'] == SCHEMA_VERSION
      raise ArgumentError, 'README 不允许使用 <details>' if readme.downcase.include?('<details')
      generated_body = generated_body!(readme)

      sites = []
      categories = Array(catalog['categories'])
      categories.each do |category|
        Array(category['subcategories']).each do |subcategory|
          Array(subcategory['sites']).each do |site|
            validate_site!(site)
            sites << site
          end
        end
      end

      raise ArgumentError, '公开网站不能为空' if sites.empty?
      raise ArgumentError, 'site_count 与实际网站数不一致' unless catalog['site_count'] == sites.length
      raise ArgumentError, 'category_count 与实际分类数不一致' unless catalog['category_count'] == categories.length

      urls = sites.map { |site| site.fetch('url') }
      duplicate_urls = urls.group_by(&:itself).select { |_url, values| values.length > 1 }.keys
      raise ArgumentError, "公开 URL 重复: #{duplicate_urls.join(', ')}" unless duplicate_urls.empty?

      validate_no_secrets!(catalog)
      validate_no_secrets!(readme)

      validate_generated_rows!(generated_body, sites)

      forbidden = find_forbidden_keys(catalog)
      raise ArgumentError, "公开数据包含内部字段: #{forbidden.join(', ')}" unless forbidden.empty?
      true
    end

    def generated_body!(readme)
      start_count = readme.scan(START_MARKER).length
      end_count = readme.scan(END_MARKER).length
      unless start_count == 1 && end_count == 1
        raise ArgumentError, 'README 自动生成标记必须各出现一次'
      end

      start_index = readme.index(START_MARKER)
      end_index = readme.index(END_MARKER)
      raise ArgumentError, 'README 自动生成标记顺序错误' if end_index < start_index

      trailing = readme[(end_index + END_MARKER.length)..]
      raise ArgumentError, 'README 结束标记后不允许存在其他内容' unless trailing.to_s.strip.empty?

      body = readme[(start_index + START_MARKER.length)...end_index]
      raise ArgumentError, 'README 自动生成主体不能为空' if body.to_s.strip.empty?
      if body.match?(%r{<thead\b|<th\b}i) || body.include?('| 网站 | 简介')
        raise ArgumentError, 'README 自动生成主体不允许表头'
      end

      body
    end

    def validate_generated_rows!(generated_body, sites)
      expected_rows = sites.map do |site|
        <<~ROW.chomp
          <tr>
          <td><a href="#{CGI.escapeHTML(site.fetch('url'))}">#{CGI.escapeHTML(site.fetch('name'))}</a></td>
          <td>#{CGI.escapeHTML(site.fetch('description'))}</td>
          </tr>
        ROW
      end
      actual_rows = generated_body.scan(
        %r{<tr>\s*<td><a href="[^"]*">.*?</a></td>\s*<td>.*?</td>\s*</tr>}m
      )

      unless generated_body.scan(%r{<tr\b}i).length == sites.length &&
             generated_body.scan(%r{<td\b}i).length == sites.length * 2 &&
             actual_rows == expected_rows
        raise ArgumentError, 'README 自动生成主体内容与 navigation.json 不一致'
      end

      true
    end

    def validate_site!(site)
      raise ArgumentError, '公开网站字段不符合白名单' unless site.keys.sort == SITE_FIELDS.sort
      uri = URI.parse(site.fetch('url'))
      unless %w[http https].include?(uri.scheme&.downcase) && uri.host && !uri.host.empty?
        raise ArgumentError, "公开 URL 必须是 HTTP(S): #{site['url']}"
      end
      raise ArgumentError, "公开 URL 不允许包含用户凭据: #{site['url']}" if uri.userinfo
      raise ArgumentError, "公开 URL 不允许包含 fragment: #{site['url']}" if uri.fragment

      query_keys = URI.decode_www_form(uri.query.to_s).map do |key, _value|
        key.downcase.gsub(/[^a-z0-9]/, '')
      end
      sensitive = query_keys & SENSITIVE_QUERY_KEYS
      raise ArgumentError, "公开 URL 包含敏感查询参数 #{sensitive.join(', ')}: #{site['url']}" unless sensitive.empty?

      true
    rescue URI::InvalidURIError, ArgumentError => error
      raise error if error.is_a?(ArgumentError) && error.message.start_with?('公开 URL')

      raise ArgumentError, "公开 URL 必须是 HTTP(S): #{site['url']}"
    end

    def validate_no_secrets!(value)
      strings = case value
                when Hash
                  value.values
                when Array
                  value
                when String
                  raise ArgumentError, '公开数据包含疑似密钥，已停止验证' if SECRET_PATTERNS.any? { |pattern| value.match?(pattern) }
                  []
                else
                  []
                end
      strings.each { |child| validate_no_secrets!(child) }
      true
    end

    def find_forbidden_keys(value, result = [])
      case value
      when Hash
        value.each do |key, child|
          result << key if FORBIDDEN_FIELDS.include?(key)
          find_forbidden_keys(child, result)
        end
      when Array
        value.each { |child| find_forbidden_keys(child, result) }
      end
      result.uniq.sort
    end
  end
end

if $PROGRAM_NAME == __FILE__
  root = if ARGV[0]
           File.expand_path(ARGV[0], Dir.pwd)
         else
           File.expand_path('..', __dir__)
         end
  PublicRepo::Validator.validate_repository!(root)
  puts "验证通过：#{File.join(root, 'README.md')} 与 data/navigation.json 一致"
end
