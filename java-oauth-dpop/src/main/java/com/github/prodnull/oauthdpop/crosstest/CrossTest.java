package com.github.prodnull.oauthdpop.crosstest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.prodnull.oauthdpop.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public class CrossTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String METHOD = "POST";
    private static final String TARGET = "https://cross-test.example.com/token";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: CrossTest <generate|validate> [proof_file]");
            System.exit(1);
        }

        try {
            switch (args[0]) {
                case "generate":
                    String outputFile = args.length > 1 ? args[1] : "java_proof.json";
                    generate(outputFile);
                    break;
                case "validate":
                    if (args.length < 2) {
                        System.err.println("Usage: CrossTest validate <proof_file>");
                        System.exit(1);
                    }
                    validate(args[1]);
                    break;
                default:
                    System.err.println("Unknown command: " + args[0]);
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void generate(String outputFile) throws Exception {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof(METHOD, TARGET, null);

        ObjectNode data = MAPPER.createObjectNode();
        data.put("proof", proof);
        data.put("thumbprint", client.getThumbprint());
        data.put("method", METHOD);
        data.put("target", TARGET);

        MAPPER.writerWithDefaultPrettyPrinter().writeValue(new File(outputFile), data);
        System.out.println("Generated proof: " + outputFile);
    }

    private static void validate(String inputFile) throws Exception {
        String json = Files.readString(Path.of(inputFile));
        var data = MAPPER.readTree(json);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(300) // 5 minutes for cross-language tests
                .requireNonce(false)
                .expectedMethod(data.get("method").asText())
                .expectedTarget(data.get("target").asText())
                .build();

        try {
            String thumbprint = DPoPValidator.validateProof(data.get("proof").asText(), config);
            DPoPValidator.verifyBinding(thumbprint, data.get("thumbprint").asText());
            System.out.println("PASS: " + inputFile + " validated successfully");
            System.exit(0);
        } catch (DPoPValidationException e) {
            System.err.println("FAIL: " + e.getCode() + ": " + e.getMessage());
            System.exit(1);
        }
    }
}
