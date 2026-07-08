import csv
import json
from pathlib import Path

try:
    import pandas as pd
except Exception:
    pd = None


def export_records(records, output_file, fmt="json"):

    output_file = Path(output_file)

    fmt = fmt.lower()

    if fmt == "json":

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)

        return str(output_file)

    if fmt == "csv":

        if not records:
            output_file.write_text("")
            return str(output_file)

        with output_file.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=records[0].keys(),
            )

            writer.writeheader()

            writer.writerows(records)

        return str(output_file)

    if fmt == "parquet":

        if pd is None:
            raise RuntimeError(
                "Install pandas and pyarrow for parquet export."
            )

        pd.DataFrame(records).to_parquet(output_file)

        return str(output_file)

    raise ValueError(fmt)
