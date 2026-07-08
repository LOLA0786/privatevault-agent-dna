from agent_dna.audit import export_records

records = [

    {
        "decision_id":"1",
        "status":"approved",
        "risk":0.02
    },

    {
        "decision_id":"2",
        "status":"blocked",
        "risk":0.91
    },

]

export_records(records,"audit.json","json")
export_records(records,"audit.csv","csv")
export_records(records,"audit.parquet","parquet")

print("Audit export complete.")
