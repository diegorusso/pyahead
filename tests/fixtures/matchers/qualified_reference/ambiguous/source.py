choose_target = False

if choose_target:
    from targetpkg import old_attr as selected
else:
    from replacement import old_attr as selected

value = selected
