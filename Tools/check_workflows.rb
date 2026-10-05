#!/usr/bin/env ruby
# frozen_string_literal: true

require 'psych'

abort 'usage: check_workflows.rb WORKFLOW.yml [...]' if ARGV.empty?
ARGV.each do |path|
  Psych.parse_file(path)
  puts "#{path}: YAML syntax OK"
end
