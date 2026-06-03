const fs = require("fs");
const path = require("path");
const { analyzeChallenge } = require("../desktop/analyzer");

const DEFAULT_SAMPLE = path.resolve(__dirname, "..", "tmp", "input", "a05ed035-b476-49d6-9b32-462ff13c5944.zip");
const DEFAULT_EXPECTED_FLAG = "flag{96efd0a2037d06f34199e921079778ee}";

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

async function main() {
  const samplePath = path.resolve(process.env.CTF_COMPASS_SAMPLE || DEFAULT_SAMPLE);
  const expectedFlag = process.env.CTF_COMPASS_EXPECTED_FLAG || DEFAULT_EXPECTED_FLAG;

  if (!fs.existsSync(samplePath)) {
    console.log(`Analyzer smoke skipped: sample not found at ${samplePath}`);
    return;
  }

  const outputRoot = path.resolve(__dirname, "..", "tmp", "smoke", String(Date.now()));
  const result = await analyzeChallenge(
    {
      title: "smoke F5 JPEG",
      description: "Regression sample for ZIP -> JPEG F5 -> pseudo-encrypted ZIP -> flag.txt.",
      notes: "password abc123",
      artifacts: [samplePath],
    },
    outputRoot,
  );

  const flags = (result.flagCandidates || []).map((item) => item.value);
  if (!flags.includes(expectedFlag)) {
    fail(`Analyzer smoke failed: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
    return;
  }
  if (result.pipelineErrors && result.pipelineErrors.length) {
    fail(`Analyzer smoke failed: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
    return;
  }

  console.log(
    JSON.stringify(
      {
        status: result.solver?.status,
        primaryFlag: result.solver?.primaryFlag?.value,
        actionsRun: result.solver?.actionsRun,
        artifacts: result.challenge?.artifactCount,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  fail(error?.stack || error?.message || String(error));
});
