import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";

import { FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/functionComparisonExample.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import { functionComparisonResultSchema } from "../../../src/domain/functionComparisonSchemas.js";
import { functionDossierSchema } from "../../../src/domain/hopperValues.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

type Access = "READ" | "WRITE";

interface Target {
  readonly address: string;
  /** Absent when the target lies outside every named procedure. */
  readonly name?: string;
  readonly access?: Access;
}

const procedure = (address: string, name: string) => ({
  address,
  name,
  classification: null,
  body: {
    available: false,
    reason: "The fixture omits function-body extent observations.",
  },
});

const kind = (access: Access) => ({
  available: true,
  provenance: "ghidra-reference-manager",
  type: access,
  flow: false,
  call: false,
  jump: false,
  data: true,
  read: access === "READ",
  write: access === "WRITE",
  indirect: false,
  computed: false,
  conditional: false,
  terminal: false,
  primary: true,
  operand_index: 0,
  external: false,
});

/** One complete `main` observation of `artifact` with an outgoing data reference per target. */
const observe = (artifact: string, targets: readonly Target[]) => {
  const template = FUNCTION_COMPARISON_EXAMPLE.left;
  return createEvidence(
    {
      path: `/tmp/function-${artifact}`,
      sha256: artifact.repeat(64),
      format: "mach-o",
    },
    template.provider,
    {
      operation: "analyze_function",
      parameters: template.parameters,
      result: jsonValueSchema.parse({
        ...functionDossierSchema.parse(template.normalized_result),
        outgoing_references: targets.map(
          ({ address, name, access = "READ" }) => ({
            source_address: "0x1000",
            target_address: address,
            source_procedure: procedure("0x1000", "main"),
            target_procedure:
              name === undefined ? null : procedure(address, name),
            kind: kind(access),
          }),
        ),
      }),
      confidence: template.confidence,
      authority: template.authority,
      relationshipCoverage: { status: "complete" },
    },
  );
};

it("identifies unnamed reference endpoints by address only within one artifact", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Function comparison must not launch a provider");
  });
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "reference-endpoint-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const compare = async (
      left: ReturnType<typeof observe>,
      right: ReturnType<typeof observe>,
    ) => {
      const response = await client.callTool({
        name: "compare_functions",
        arguments: { left, right },
      });
      expect(
        response.isError,
        JSON.stringify(response.structuredContent),
      ).not.toBe(true);
      const result = functionComparisonResultSchema.parse(
        parseEvidence(response.structuredContent).normalized_result,
      );
      const references = result.dimensions.find(
        ({ dimension }) => dimension === "references",
      );
      expect(references?.evidence_links).toEqual([
        left.evidence_id,
        right.evidence_id,
      ]);
      return { status: result.status, references };
    };

    // Within one artifact, recorded addresses identify unnamed endpoints.
    const moved = await compare(
      observe("a", [{ address: "0x2000" }]),
      observe("a", [{ address: "0x3000" }]),
    );
    expect(moved).toMatchObject({
      status: "changed",
      references: { status: "changed" },
    });
    expect(moved.references?.left_digest).not.toBe(
      moved.references?.right_digest,
    );
    expect(
      await compare(
        observe("a", [{ address: "0x2000" }]),
        observe("a", [{ address: "0x02000" }]),
      ),
    ).toMatchObject({
      status: "unchanged",
      references: { status: "unchanged" },
    });
    expect(
      await compare(
        observe("a", [
          { address: "0x2000", access: "READ" },
          { address: "0x3000", access: "WRITE" },
        ]),
        observe("a", [
          { address: "0x2000", access: "WRITE" },
          { address: "0x3000", access: "READ" },
        ]),
      ),
    ).toMatchObject({ status: "changed", references: { status: "changed" } });

    // Named endpoints keep matching by name, so relocation alone is no change.
    expect(
      await compare(
        observe("a", [{ address: "0x2000", name: "first" }]),
        observe("a", [{ address: "0x3000", name: "second" }]),
      ),
    ).toMatchObject({ status: "changed", references: { status: "changed" } });
    expect(
      await compare(
        observe("a", [{ address: "0x2000", name: "helper" }]),
        observe("a", [{ address: "0x3000", name: "helper" }]),
      ),
    ).toMatchObject({
      status: "unchanged",
      references: { status: "unchanged" },
    });
    expect(
      await compare(
        observe("a", [{ address: "0x2000", name: "helper" }]),
        observe("b", [{ address: "0x3000", name: "helper" }]),
      ),
    ).toMatchObject({
      status: "unchanged",
      references: { status: "unchanged" },
    });

    // Across artifacts, unnamed endpoint identity is unresolved.
    expect(
      await compare(
        observe("a", [{ address: "0x2000" }]),
        observe("b", [{ address: "0x3000" }]),
      ),
    ).toMatchObject({
      status: "unknown",
      references: {
        status: "unknown",
        left_count: 1,
        right_count: 1,
        limitations: [
          expect.stringContaining("does not align across different artifacts"),
        ],
      },
    });
    // A known fact that differs is a change under any pairing of unnamed endpoints.
    expect(
      await compare(
        observe("a", [{ address: "0x2000", access: "READ" }]),
        observe("b", [{ address: "0x2000", access: "WRITE" }]),
      ),
    ).toMatchObject({ status: "changed", references: { status: "changed" } });
  } finally {
    await Promise.allSettled([client.close(), server.close(), session.close()]);
  }
});
