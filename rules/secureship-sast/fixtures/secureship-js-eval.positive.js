// Positive fixture: eval with dynamic user expression
function executeExpression(userCode) {
  return eval(userCode);
}

function constructFunction(code) {
  return new Function("a", "b", code);
}
