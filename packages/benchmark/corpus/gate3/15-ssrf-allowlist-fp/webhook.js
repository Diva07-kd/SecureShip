export async function callWebhook(url) {
  const parsed = new URL(url);
  if (parsed.hostname !== 'api.trusted.com') throw new Error('Forbidden');
  return fetch(url);
}
