// Negative fixture: eval with static constant literals
function safeStaticEval() {
  return eval("2 + 2");
}

function safeStaticFunction() {
  return new Function("a", "b", "return a + b");
}
