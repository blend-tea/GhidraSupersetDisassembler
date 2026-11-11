package amace.ui;

import amace.core.Candidate;

/** Snapshot strings: table rendering never reads or changes the live Program. */
record CandidateRow(Candidate candidate, String pointerFacts, String stackFacts,
        String registerFacts, String selection, String details) {}
