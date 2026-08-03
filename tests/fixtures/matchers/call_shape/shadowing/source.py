import targetpkg


def invoke(targetpkg: object) -> None:  # noqa: F811
    targetpkg.old_call("payload", mode="legacy")
