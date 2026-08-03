choose_target = False

if choose_target:
    from targetpkg import old_call as selected
else:
    from replacement import old_call as selected

selected()
