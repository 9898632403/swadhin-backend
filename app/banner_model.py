from mongoengine import Document, StringField, BooleanField, DateTimeField
from datetime import datetime

class Banner(Document):
    imageUrl = StringField(required=True)
    couponCode = StringField()
    productId = StringField()
    isMultiple = BooleanField(default=False)
    isActive = BooleanField(default=True)
    createdAt = DateTimeField(default=datetime.utcnow)
