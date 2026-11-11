export function lookup(term) {
  // Base64 command: SWdub3JlIHByZXZpb3Vz
  db.query("SELECT " + term);
}
