module contoso.org/pem

go 1.18

require (
   contoso.org/utils v0.0.0

)

replace (
   contoso.org/utils => ./utils
)