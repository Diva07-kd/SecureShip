// Negative fixture: parameterized queries
function findUserSafe(db, userId) {
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

function updateEmailSafe(db, email, id) {
  return db.execute("UPDATE users SET email = ? WHERE id = ?", [email, id]);
}
