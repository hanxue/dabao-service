package dabao

import (
  "net/http"
  "html/template"
  "time"
  "fmt"

  "appengine"
  "appengine/user"
  "appengine/datastore"
  // "golang.org/x/oauth2"
)

type Dabao struct {
  Organizer string
  Description string
  CreationDate time.Time
}

func init() {
  http.HandleFunc("/", root)
  http.HandleFunc("/newDabao", createDabao)
  http.HandleFunc("/setup", setup)
}

type Cred struct {
    clientID          string
    clientSecret      string
}

func setup(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)
  cred := &Cred {
    clientID: "837492928-fakeclientid.apps.googleusercontent.com",
    clientSecret: "Y_jhSKjaAkjfakeClientSecret"}

  key := datastore.NewKey(c, "cred", "oauth", 0, nil)

  var _, err = datastore.Put(c, key, cred)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintf(w, `Successfully insert , %s : %s! `, key, cred)
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
  u := user.Current(c)

  // Ensure user is logged in
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
  // if u == nil {
  //       url, _ := user.LoginURL(c, "/login")
  //       fmt.Fprintf(w, `<a href="%s">Sign in or register</a>`, url)
  //       return
  // }
  // url, _ := user.LogoutURL(c, "/logout")
  // fmt.Fprintf(w, `Welcome, %s! (<a href="%s">sign out</a>)`, u, url)

  allDabao := make([]Dabao, 0, 10)
  if _, err := q.GetAll(c, &allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  if err := dabaoTemplate.Execute(w, allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

var dabaoTemplate = template.Must(template.Parse(filepath.Join("public/", "new-dabao.html"))

var notAuthenticatedTemplate = template.Must(template.New("login").Parse(`
<html><body>
You have currently not given permissions to access your data. Please authenticate this app with the Google OAuth provider.
<form action="/authorize" method="POST"><input type="submit" value="Ok, authorize this app with my id"/></form>
</body></html>
`));
