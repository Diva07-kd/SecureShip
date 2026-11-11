const key = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
export function encrypt(data) {
  return crypto.createCipheriv('aes-128-cbc', key, iv);
}
