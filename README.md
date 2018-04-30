# VpWebApi

VpWebApi contient deux web service :

  -/api/authenticate : qui prend en paramètre  (email,password) pour authentifié le user seulement à base d'un controle
        si l'email et le password sont valide 
  
  
  -/api/confidentials : prend en paramètre  (email) et pour authentifier  le user la methode 
   http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html a été implémenter 
   
   et pour cela je me suis servie de l'exemple fournie par amazone : https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-examples-using-sdks.html
   
   pour créer  la signature,
  
   et pour intercepter la requête  j'ai créé  un custom attribute pour le Controller  Confidentials :
   AuthentificationFilter : Attribute, IAuthenticationFilter 
   
   qui implémente  IAuthenticationFilter
   
   lorsque  je reçois la requête  dans la méthode AuthenticateAsync
   
   je recalcule la signature et je la compare avec celle envoyé dans la requête,
   si elles sont identiques je l'accepte sinon rejeté 
   
   
