/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
chpasswd(user,pwd) = {
  cmd = strprintf("yes %s | passwd %s",pwd,user);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
}
change_password(user,modulus,e=7) = {
  iferr(
    pwd = randompwd(10);
    chpasswd(user, pwd);
    address = strprintf("%s@cryptoflop.org",user);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user %s",user);
  ,E,print("[ERROR] ",E));
}




coder(clair)={
	vecDeb=Vec(Vecsmall(clair));
	code=fromdigits(Vec(vec),128);
	return(code);
}
decoder(mCode)={
	
	clR=Strchr(digits(mCode,128));
	return(clR);
}


\\ Récupération des entrées
in = readvec("input.txt");
n=in[1][1];
e=in[1][2];
chiffre=in[2];


\\Construction du message codé stéréotype:


debut="Cher collaborateur, votre nouveau mot de passe est ";
codeDebut=fromdigits(Vec(Vecsmall(debut)),128);

fin=". Merci de votre comprehension, le service informatique.";
codeFin=fromdigits(Vec(Vecsmall(fin)),128);

v1=Vec(Vecsmall(debut));

v2=Vec(Vecsmall(fin));

tmp=Vec(0,10);
v1=concat(concat(v1,tmp),v2);  \\ créé le vecteur [début du message en base 128, 10 places pour le mot de passe en base 128, fin du message en base 128] 
c1=fromdigits(Vec(v1),128);    \\ c1 est donc le chiffré d'un message sans mot de passe, mais avec la place pour celui-ci tout de même



\\ Le mot de pas est composé de 10 caractère, et donc, codé en base 128, le code est inférieur à 128^10 d'où le troisième paramètre de la fonction zncoppersmith
\\ On cherche à résoudre (c1+128^(#v2)*x)^e-chiffre=0
\\ Comme le mot de passe se trouve au milieu du texte, il est nécessaire de la multiplier par 128^(cardinal de la fin du texte) pour que celui-ci vienne se placer au bonne endroit dans le texte.

codeMdp=zncoppersmith( ( 128^(#v2)*x + c1 )^e - chiffre , n , 128^10 );
\\reconstitution du message complet
fullMessage=concat( concat (debut,decoder(codeMdp[1])),fin);
print(fullMessage);



