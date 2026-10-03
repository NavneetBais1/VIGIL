def __init__(self):

    # Create Vigil's application-data directory.
    os.makedirs(
        VIGIL_DATA_DIR,
        exist_ok=True
    )

    # Move an existing development config into the
    # proper Windows application-data location.
    self._migrate_legacy_config()

    self.config = self._load_config()