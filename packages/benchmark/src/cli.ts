import { BenchmarkRunner } from './runner.js';

async function main() {
  const runner = new BenchmarkRunner();
  const args = process.argv.slice(2);
  const modeIdx = args.indexOf('--mode');
  const mode = modeIdx !== -1 && args[modeIdx + 1] ? args[modeIdx + 1]!.toLowerCase() : 'all';

  if (mode === 'replay') {
    const res = await runner.runReplay();
    BenchmarkRunner.printResults(res);
    if (!res.passed) process.exit(1);
    return;
  }

  if (mode === 'live') {
    const res = await runner.runLive();
    BenchmarkRunner.printResults(res);
    if (!res.passed) process.exit(1);
    return;
  }

  // Default / 'all': run both and compare side-by-side
  const replayRes = await runner.runReplay();
  BenchmarkRunner.printResults(replayRes);

  const liveRes = await runner.runLive();
  BenchmarkRunner.printResults(liveRes);

  BenchmarkRunner.printComparison(replayRes, liveRes);

  if (!replayRes.passed || !liveRes.passed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Benchmark execution error:', err);
  process.exit(1);
});
