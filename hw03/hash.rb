#!/usr/bin/env ruby

require 'openssl'

filename = ARGV[0]
expected = ARGV[1]

puts "reading file: #{filename}"

def file_blocks(filename)
  buffers = []

  file = File.new(filename, 'r')
  while (buffer = file.read(1024)) do
    buffers <<  buffer
  end
  file.close

  buffers
end

def sha(st)
  sha256 = Digest::SHA256.new
  sha256.update(st)
  sha256.hexdigest.chars.each_slice(2).map(&:join).map(&:hex).pack('c*')
end

def to_hex(st)
  st.map {|n| n.to_s(16).rjust(2, '0') }.join
end

hash = file_blocks(filename).reverse.inject('') do |res, block|
  sha(block + res)
end

result = to_hex(hash.bytes)

puts "Hash: #{result}"

unless expected.nil?
  puts "Checksum result: #{expected == result ? "OK" : "BAD"}"
end
