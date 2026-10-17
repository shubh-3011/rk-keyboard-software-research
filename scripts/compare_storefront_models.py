#!/usr/bin/env python3
"""Compare dated RK storefront model tokens with the installed profile names."""

import csv
import json
import re
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "rk-public-storefront-models.csv"
CATALOG = ROOT / "models.json"
OUTPUT = ROOT / "docs" / "rk-storefront-model-crosswalk.csv"


def main() -> None:
    with SOURCE.open(newline="", encoding="utf-8") as stream:
        listing_rows = list(csv.DictReader(stream))
    with CATALOG.open(encoding="utf-8") as stream:
        models = json.load(stream)["models"]

    listings_by_token: dict[str, list[str]] = defaultdict(list)
    for row in listing_rows:
        label = row["storefront_label"].strip()
        if label and label not in listings_by_token[row["model_token"]]:
            listings_by_token[row["model_token"]].append(label)

    fields = [
        "model_token",
        "storefront_labels",
        "profile_name_token_match",
        "candidate_profile_codes",
        "candidate_profile_names",
        "interpretation",
    ]
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for token, labels in listings_by_token.items():
            pattern = re.compile(
                r"(?<![A-Z0-9])" + re.escape(token.upper()) + r"(?![A-Z0-9])"
            )
            matches = [
                model
                for model in models
                if pattern.search(
                    (model.get("name", "") + " " + model.get("family", "")).upper()
                )
            ]
            writer.writerow(
                {
                    "model_token": token,
                    "storefront_labels": "; ".join(labels),
                    "profile_name_token_match": "yes" if matches else "no",
                    "candidate_profile_codes": "; ".join(
                        model["code"] for model in matches
                    ),
                    "candidate_profile_names": "; ".join(
                        model["name"] for model in matches
                    ),
                    "interpretation": (
                        "Name-token candidates only; software selection and hardware compatibility unproven."
                        if matches
                        else "No exact profile name token; mapping to this package unresolved."
                    ),
                }
            )
    print(
        "Wrote {} model-token rows from {} storefront labels to {}".format(
            len(listings_by_token), len(listing_rows), OUTPUT.relative_to(ROOT)
        )
    )


if __name__ == "__main__":
    main()
