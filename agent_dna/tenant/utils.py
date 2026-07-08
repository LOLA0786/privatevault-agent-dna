def tenant_prefix(ctx):

    return (
        f"{ctx.tenant_id}/"
        f"{ctx.organization_id}/"
        f"{ctx.project_id}"
    )
