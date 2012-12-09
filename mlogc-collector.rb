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

require 'rubygems'
require 'sinatra'
require 'pp'
require 'parser'
require 'json'

module Mlogc
  class Collector < Sinatra::Base
    configure :production,:development do
      enable :logging
    end
    put '/collector' do
      str = request.body.read 
      parser = Parser.new str
      logger.info str
      out = {:audit => parser.audit,
        :request => parser.request,
        :request_headers => parser.req_headers,
        :response => parser.response,
        :response_headers => parser.resp_headers,
        :request_body => parser.req_body
      }
      logger.info JSON.pretty_generate out
    end
    
    get '/' do
      "hello, world"
    end
    run! if app_file == $0
  end
end
