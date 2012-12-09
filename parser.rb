# Copyright (c) 2012 Ian Delahorne <ian.delahorne@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'rubygems' require 'rack/utils'

module Mlogc
  class Parser 
    
    $phase_regex = /^--([0-9a-fA-F]{8,})-([A-Z])--$/
    $phase_mapping = {:A => "audit_log_header",
      "B" => "request_headers",
      "C" => "request_body",
      # :D => "intended_response_headers",
      #  :E => "indended_response_body",
      "F" => "response_headers",
      #  :G => "response_body",
      "H" => "audit",
      "I" => "multipart_request_body",
      # :J => "multipart_files_information"
      "K" => "matched_rules",
      "Z" => "footer"
    }
    attr_accessor :request, :req_headers, :response, :resp_headers, :req_body, :audit

    def parse_header(line, request, headers)
      puts "parse_header req #{request}"
      line.chomp!
      return if line.match /^\s*$/
      if line.match /^(GET|POST|PUT|HEAD)/ or line.match /^HTTP/
        request = line
        puts "asdf #{request}"
        return
      end
      
      (key,value) = line.split(": ", 2)
      if !key or !value
        puts "parse_header - error with line #{line}"
      end
      if !headers.has_key? key
        headers[key] = value
      elsif headers[key].is_a? String
        headers[key] = [headers[key], value]
      elsif headers[key].is_a? Array
        headers[key] << vlaue
      end
    end

    def parse_req_headers(line)
      puts 'parse_req_headers'
     parse_header(line, @request, @req_headers)
    end

    def parse_resp_headers(line)
      puts 'parse_resp_headers'
      parse_header(line, response, resp_headers)
    end
    
    def parse_req_body(line)
      @req_body = Rack::Utils.parse_query(line)
    end

    def parse_audit(line)
      parse_header(line, nil, @audit)
    end
    def parse_multipart_body(line)
        puts "parse_multipart_body #{line}"
    end
    def parse_matched_rules(line)
      puts "parse_matched_rules #{line}"
    end
    
    def parse_audit_header(line)
      matchdata = line.match /\[(.*)\] ([a-zA-Z0-9-]+) ([0-9\.]+) ([0-9]+) ([0-9\.]+) ([0-9]+)/
      if matchdata 
        @audit["timestamp"] = matchdata[1]
        @audit["id"] = matchdata[2]
        @audit["source_ip"] = matchdata[3]
        @audit["source_port"] = matchdata[4]
        @audit["dest_ip"] = matchdata[5]
        @audit["dest_port"] = matchdata[6]
      else
        puts "parse_audit_header #{line}"
      end
    end
    def parse_line(phase, line) 
      case phase
      when "A"
        parse_audit_header(line)
      when "B" 
        parse_req_headers(line)
      when "C"
        parse_req_body(line)
      when "F"
        parse_resp_headers(line)
      when "H"
        parse_audit(line)
      when "I"
        parse_multipart_body(line)
      when "K"
        parse_matched_rules(line)
      else
        puts "In phase #{phase}, don't know what to do"
      end
    end
    
    def parse(input)
      input.each_line do |line|
        match = line.match($phase_regex)
        if match
          @id = match[1]
          @phase = match[2]
        else
          parse_line(@phase, line)
        end
      end
    end
    def fix_audit
      return if !@audit.has_key? "Message"
      message = @audit["Message"]
      matchdata =  message.match /\[file "(.*)"\] \[line "(.*)"\]/
      if matchdata
        @audit["file"] = matchdata[1]
        @audit["line"] = matchdata[2]
      end
      matchdata = nil
      matchdata = message.match /Access denied with redirection to (.*) using .* (?:Pattern m|M)atch of \"(.*)\" against \"(.*)\" required/
      if matchdata
        @audit["redirect"] = matchdata[1]
        @audit["pattern"] = matchdata[2]
        @audit["against"] = matchdata[3]
      else
        matchdata = message.match /.*404.*Pattern match \"(.*)\" at/
        if matchdata 
          @audit["pattern"] = matchdata[1]
        end
      end
    end
    def initialize(input)
      @audit = Hash.new
      @req_body = Hash.new
      @response = ""
      @resp_headers = Hash.new
      @request = ""
      @req_headers = Hash.new
      @phase = nil
      @id =  ""
      @entry = Hash.new
      parse(input)
      puts "request #{@request}"
      puts "resp #{@response}"
      fix_audit
    end
  end  
end

