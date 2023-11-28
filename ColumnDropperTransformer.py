class ColumnDropperTransformer():
    def __init__(self, columns):
        self.columns = columns

    def transform(self, x, y=None):
        return x.drop(self.columns, axis=1)

    def fit(self, x, y=None):
        return self
