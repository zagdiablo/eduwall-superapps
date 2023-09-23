from app import create_app
import webview


app = create_app()


if __name__ == "__main__":
    webview.create_window("Eduwall SupperApps", app, width=367, height=690)
    webview.start()
