# Rebuild graphs after the identity encoding fix

The identity encoding fix changes package IDs that contain escaped characters and all evidence IDs, including enrichment claims. It also changes affected edge IDs and inline-license hashes. Existing graphs require a full replay into a new, empty graph. Replaying into the existing graph leaves obsolete nodes and duplicate evidence.

1. Stop ingestion into the existing graph.
2. Preserve the source documents, enrichment configuration, and historical enrichment snapshots needed to reproduce the graph.
3. Create a new, empty Varve graph through your deployment's graph administration interface.
4. Configure Sluice to write to the new graph.
5. Replay every source document with the updated Sluice binary. Replay historical enrichment snapshots where historical claims are required.
6. Verify that replay completes without failed documents or enrichment failures. Check representative package, vulnerability, and dependency queries against the source documents.
7. Switch graph readers to the new graph.
8. Retain the previous graph until you have verified the replacement and completed your retention requirements.

Do not derive replacement IDs from old IDs alone. Old IDs can represent multiple distinct packages or evidence records because their field boundaries were ambiguous. Recover those distinctions from the original source documents. Live enrichment cannot reconstruct historical responses that were not retained.

For rollback, switch readers to the retained graph and restore the previous ingestion binary and configuration together.
