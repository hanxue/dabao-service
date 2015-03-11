package dabao

import (
  "net/http"
  "html/template"
  "time"

  "appengine"
  "appengine/user"
  "appengine/datastore"
)

type Dabao struct {
  Id int64
  Organizer string
  Description string
  CreationDate time.Time
}

func init() {
  http.HandleFunc("/", root)
  http.HandleFunc("/newDabao", createDabao)
}

// dabaoKey returns the key used for all dabao sessions
func dabaoKey(c appengine.Context) *datastore.Key {
  return datastore.NewKey(c, "Dabao", "dabao_0.1", 0, nil)
}

func createDabao(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)  
  d := Dabao {
    Description: r.FormValue("Description"),
    CreationDate: time.Now(),
  }
  

  u := user.Current(c)
  if u != nil {
    d.Organizer = u.String()
  } else {
    d.Organizer = "Anonymous"
  }

  key := datastore.NewIncompleteKey(c, "Dabao", dabaoKey(c))
  var _, err = datastore.Put(c, key, &d)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  http.Redirect(w, r, "/", http.StatusFound)
}

func root(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)
  q := datastore.NewQuery("Dabao").Ancestor(dabaoKey(c)).Order("-CreationDate").Limit(10)

  allDabao := make([]Dabao, 0, 10)
  if _, err := q.GetAll(c, &allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  if err := dabaoTemplate.Execute(w, allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

var dabaoTemplate = template.Must(template.New("dabao").Parse(`
<html>
  <head>
    <title>Dabao Service</title>
  <head>
  <body>
    <form action="/newDabao" method="post">
      <div><textarea name="Description" rows="3" cols="60"></textarea></div>
      <div><input type="submit" value="New Dabao"></div>
    </form>
    {{range .}}
      <p><b>{{.Organizer}}</b> created:</p>
      <pre>{{.Description}}</pre>
    {{end}}
  </body>
</html>
`))
