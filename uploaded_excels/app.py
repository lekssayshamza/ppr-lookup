
from flask import Flask, render_template, request
import pandas as pd

app = Flask(__name__)

# Load Excel data once
df = pd.read_excel('data/employees.xlsx')

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        search_input = request.form['search_input'].strip().lower()
        match = df[df['Name'].str.lower().str.contains(search_input) | df['CIN'].astype(str).str.contains(search_input)]

        if not match.empty:
            result = match[['Name', 'CIN', 'PPR']].to_dict(orient='records')
        else:
            result = "No match found."

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
