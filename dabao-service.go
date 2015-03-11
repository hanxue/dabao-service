package dabao

import (
  "fmt"
  "net/http"
  "html/template"
  "time"

  "appengine"
  "appengine/user"
)

type Dabao struct {
  Id int64
  Description string
  CreationDate time.Time
}
func init() {
  http.HandleFunc("/", root)
  http.HandleFunc("/newDabao", createDabao)
}

func createDabao(w http.ResponseWriter, r *http.Request) {
  err := dabaoTemplate.Execute(w, r.FormValue("Description"))
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
  c := appengine.NewContext(r)  
  u := user.Current(c)
  if u == nil {
    url, err := user.LoginURL(c, r.URL.String())
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
    w.Header().Set("Location", url)
    w.WriteHeader(http.StatusFound)
    return
  }
  fmt.Fprintf(w, "Dabao initiated by %v!", u)
}

func root(w http.ResponseWriter, r *http.Request) {
  fmt.Fprint(w, newDabaoForm)
}

var dabaoTemplate = template.Must(template.New("dabao").Parse(dabaoTemplateHTML))

const dabaoTemplateHTML = `
<html>
  <body>
    <p>Created Dabao:</p>
    <pre>{{.}}</pre>
  </body>
</html>
`

const newDabaoForm = `
<html>
  <body>
    <h1>Enter Dabao description</h1>
    <form action="/newDabao" method="post">
      <div><textarea name="Description" rows="3" cols="60"></textarea></div>
      <div><input type="submit" value="New Dabao"></div>
    </form>
  </body>
</html>
`
