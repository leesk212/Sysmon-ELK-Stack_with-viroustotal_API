
import SeokMin_ui as SKM

if __name__ == '__main__':
    app = SKM.QApplication(SKM.sys.argv)
    window = SKM.Mywindow(SKM.rs)
    window.show()
    app.exec_()