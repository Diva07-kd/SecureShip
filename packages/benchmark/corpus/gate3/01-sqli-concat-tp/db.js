export function getUser(userId) {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}
