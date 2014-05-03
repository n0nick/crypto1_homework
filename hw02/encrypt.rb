require 'openssl'

DEBUG = false

BLOCK_SIZE = 16

def log(msg)
  puts msg if DEBUG
end

def array_pad(ar, size, value=0)
  to_pad = size - ar.size
  to_pad.times do
    ar.unshift(value)
  end
  ar
end

def plus1(a)
  i = a.length-1
  while a[i]>=255 do
    i-= 1
  end
  a[i]+= 1
  a
end

def xor(a, b)
  size = [a.length, b.length].max
  res = []
  0.upto(size-1) do |i|
    res.push((a[i] || 0) ^ (b[i] || 0))
  end
  res
end

def to_hex(st)
  st.map {|n| n.to_s(16).rjust(2, '0') }.join
end

def split_blocks(s)
  s.bytes.each_slice(BLOCK_SIZE).to_a.map {|b| b.pack('c*') }
end

def parse_key(k)
  k.chars.each_slice(2).map(&:join).map(&:hex).pack('c*')
end

def encrypt_cbc(k, m)
  key = parse_key(k)

  log "[encrypt] message length: #{m.length}"
  log "[encrypt] key length: #{key.length}"

  iv = OpenSSL::Random.random_bytes(BLOCK_SIZE).bytes.to_a
  log "[encrypt] iv generated: #{to_hex iv}"

  encrypted = iv

  blocks = split_blocks(m)
  log "[encrypt] blocks to encrypt: #{blocks.length}"
  log "[encrypt] blocks: #{blocks.map(&:length)}"

  # pad last block
  to_pad = BLOCK_SIZE - blocks.last.length
  if to_pad == 0
    to_pad = BLOCK_SIZE
    blocks << ""
  end
  log "[encrypt] padding: #{to_pad}"
  to_pad.times do
    blocks.last << to_pad
  end

  cipher = OpenSSL::Cipher.new("AES-128-ECB")
  cipher.encrypt
  cipher.key = key
  cipher.padding = 0

  blocks.each do |b|
    x = xor(iv, b.bytes.to_a)
    log "[encrypt] xored: #{to_hex x}"

    e = (cipher.update(x.pack('c*')) + cipher.final).bytes.to_a
    log "[encrypt] encrypted: #{to_hex e} (#{x.size} -> #{e.size})"

    encrypted.concat(e)
    iv = e
  end

  log "[encrypt] result length: #{encrypted.size}"

  result = to_hex(encrypted)
  log "[encrypt] result: #{result}"

  result
end

def decrypt_cbc(k, c)
  key = parse_key(k)

  st = c.chars.each_slice(2).map(&:join).map(&:hex).pack('c*')

  log "[decrypt] input length: #{st.size}"

  blocks = split_blocks(st)
  log "[decrypt] blocks received: #{blocks.length}"
  log "[decrypt] blocks: #{blocks.map(&:length)}"

  iv = blocks.slice!(0, 1).first
  log "[decrypt] iv found: #{to_hex iv.bytes}"
  log "[decrypt] blocks to decrypt: #{blocks.length}"

  decrypted = []

  cipher = OpenSSL::Cipher.new("AES-128-ECB")
  cipher.decrypt
  cipher.key = key
  cipher.padding = 0

  blocks.each do |b|
    log "[decrypt] decrypting: #{to_hex b.bytes}"

    d = (cipher.update(b) + cipher.final).bytes.to_a
    log "[decrypt] decrypted: #{to_hex d} (#{d.size} -> #{b.size})"

    x = xor(d, iv.bytes.to_a)
    log "[decrypt] xored: #{to_hex x}"

    decrypted.concat(x)
    iv = b
  end

  to_unpad = decrypted.last
  to_unpad.times do
    decrypted.pop
  end

  decrypted.pack('c*')
end

def encrypt_ctr(k, m)
  key = parse_key(k)

  iv = OpenSSL::Random.random_bytes(BLOCK_SIZE).bytes.to_a
  log "[encrypt] iv generated: #{to_hex iv}"

  blocks = split_blocks(m)

  cipher = OpenSSL::Cipher.new("AES-128-ECB")
  cipher.encrypt
  cipher.key = key
  cipher.padding = 0

  encrypted = iv.clone

  blocks.each do |b, index|
    log "[encrypt] iv: #{to_hex iv}"
    e = (cipher.update(iv.pack('c*')) + cipher.final).bytes.to_a
    log "[encrypt] encrypt result: #{to_hex e}"
    blob = array_pad(b.bytes.to_a, BLOCK_SIZE)
    log "[encrypt] xoring: #{to_hex e}, #{to_hex blob}"
    x = xor(e, blob)

    encrypted.concat(x)
    plus1(iv)
  end

  result = to_hex(encrypted)
  log "[encrypt] result: #{result}"

  result
end

def decrypt_ctr(k, c)
  key = parse_key(k)

  st = c.chars.each_slice(2).map(&:join).map(&:hex).pack('c*')

  log "[decrypt] input length: #{st.size}"

  blocks = split_blocks(st)
  log "[decrypt] blocks received: #{blocks.length}"
  log "[decrypt] blocks: #{blocks.map(&:length)}"

  iv = blocks.slice!(0, 1).first.bytes.to_a
  log "[decrypt] iv found: #{to_hex iv}"
  log "[decrypt] blocks to decrypt: #{blocks.length}"

  cipher = OpenSSL::Cipher.new("AES-128-ECB")
  cipher.encrypt
  cipher.key = key
  cipher.padding = 0

  decrypted = []

  blocks.each do |b, index|
    d = (cipher.update(iv.pack('c*')) + cipher.final).bytes.to_a
    log "[decrypt] decrypt result: #{to_hex d}"
    log "[decrypt] xoring: #{to_hex d}, #{to_hex b.bytes.to_a}"
    x = xor(d, b.bytes.to_a)
    log "[decrypt] xor result: #{to_hex x}"

    decrypted.concat(x)
    iv = plus1(iv)
  end

  decrypted.pack('c*')
end

def encrypt(mode, k, m)
  case mode.downcase
  when :cbc
    encrypt_cbc(k, m)
  when :ctr
    encrypt_ctr(k, m)
  else
    raise NotImplementedError.new
  end
end

def decrypt(mode, k, m)
  case mode.downcase
  when :cbc
    decrypt_cbc(k, m)
  when :ctr
    decrypt_ctr(k, m)
  else
    raise NotImplementedError.new
  end
end
