import multiprocessing
from tkinter import Button, Canvas, Entry, Label, StringVar, Tk

multiprocessing.freeze_support()


main = Tk()
main.resizable(False, False)
main.title("Kullanıcı Girişi")
main.eval("tk::PlaceWindow . center")


text_kullaniciadi = StringVar()
text_sifre = StringVar()


def cikis_btn():
    main.quit()


canvas = Canvas(main, bg="light blue", height=220, width=300)
canvas.pack()


labetl_top1 = Label(
    main,
    text="MOE Toplama Botu",
    font="verdana, 13",
    bg="light blue",
)
labetl_top1.place(x=80, y=20)

labetl_top2 = Label(
    main,
    text="By YnS & MSTF",
    font="verdana, 13",
    bg="light blue",
)
labetl_top2.place(x=90, y=50)

label_kullaniciadi = Label(main, bg="light blue", text="Kullanıcı Adı:", font="verdana 11")
label_kullaniciadi.place(x=30, y=95)
entry_kullaniciadi = Entry(main, textvariable=text_kullaniciadi)
entry_kullaniciadi.place(x=130, y=95)

label_sifre = Label(main, bg="light blue", text="Şifre:", font="verdana 11")
label_sifre.place(x=80, y=135)
entry_sifre = Entry(main, textvariable=text_sifre, show="*")
entry_sifre.place(x=130, y=135)

btn_cikis = Button(
    main,
    text="İptal Et",
    width=10,
    bg="light blue",
    font="verdana 11 bold",
    command=cikis_btn,
)
btn_cikis.place(x=25, y=180)

btn_giris = Button(main, text="Giriş", width=10, bg="light blue", font="verdana 11 bold")
btn_giris.place(x=165, y=180)


main.mainloop()
