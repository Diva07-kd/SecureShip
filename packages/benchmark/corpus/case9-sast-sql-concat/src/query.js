function getUser(db, id) { return db.query("SELECT * FROM users WHERE id = " + id); }
