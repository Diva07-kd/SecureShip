export function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = $1";
  return db.execute(query, [userId]);
}
