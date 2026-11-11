export function queryUser(q) {
  db.query("SELECT " + q);
}
