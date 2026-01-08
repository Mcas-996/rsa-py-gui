import app_window
import slint


class App(app_window.AppWindow):
    @slint.callback
    def request_increase_value(self):
        self.counter = self.counter + 1


app = App()
app.run()
