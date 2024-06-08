from ceng3544.models.user_model import user_init

class Models:
    model = None

    def __init__(self, db):
        self.user_model = user_init(db)
        Models.model = self

    def predict(self, image):
        return self.model.predict(image)