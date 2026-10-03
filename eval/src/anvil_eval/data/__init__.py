"""Corpus loaders. Each refuses a corpus whose shape is not the one it was written against."""


class CorpusError(ValueError):
    """The corpus on disk is missing, or is not shaped the way the loader requires."""
