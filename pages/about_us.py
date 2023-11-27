import streamlit as st
from PIL import Image

st.set_page_config(page_title="About Us", page_icon="🌝")

image = Image.open("image1.jpg")

st.image(image, caption="")

st.title('We are Data Wizard')
st.subheader("A coven of digital magicians creating anything wonderful from data")


st.divider()

st.write("Charisma Juni - Data Scientist Magician")
st.write("Arryanda Maulani - Data Engineer Magician")
st.write("Dendy Sugandi - IT Infrastructure Specialist Magician")
st.write("M Wiwid Setiawan - Code Magician")
st.write("Rindang Cahyaning - IT Consultant Specialist Magician")