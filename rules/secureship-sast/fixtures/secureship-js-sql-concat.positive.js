// Positive fixture: SQL built via string concatenation
function findUser(db, userId) {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}

function updateEmail(db, email, id) {
  return db.execute(`UPDATE users SET email = '${email}' WHERE id = ${id}`);
}
