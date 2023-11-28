from keras.models import Sequential
from keras.layers import Dense


def create_model(input_dim, output_dim, hidden_layer_size=64, activation='relu'):
    model = Sequential()
    model.add(Dense(hidden_layer_size, input_dim=input_dim, activation=activation))
    model.add(Dense(output_dim, activation='softmax'))
    # optimizer = keras.optimizers.Adam(learning_rate= alpha)
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model
