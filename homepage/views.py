# THOMAS ELDHO 20BCT0113
import pandas as pd
from django.shortcuts import render
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score# for accuracy 
from sklearn.model_selection import train_test_split#splitting to test and train 
import re
import whois
import requests
from datetime import datetime
from bs4 import BeautifulSoup#for getting html and javascript of a website
from csv import writer
from django.contrib import messages
from django.shortcuts import redirect
# Create your views here.
def home(request):
    return(render(request,"index.html"))
def result(request):
    def is_registered(domain_name):#to check if the domain is registered
        try:
            w = whois.whois(domain_name)
        except Exception:
            return False
        else:
            return bool(w.domain_name)
    def is_url(url): #function to check if  url exists 
        try:
            ri=requests.get(url)#returns the page for the url if its  exist
        except Exception:
            return False
        else:
                return bool(ri.url)#is true if site exists
    url=request.POST["URL"]#obtains user-input url from index.html
    r=[]#list to store the final result
    if is_url(url):
        flg=True
        y=[list()]#holds the deciding attributes
        url_part=re.split('://',url)#splits url into https+url
        domain=url_part[1]#consists eveything after https
        domain_part=re.split("/",domain)#splits domain into domain name and path
        #THOMAS ELDHO 20BCT0113
        dn=domain_part[0]#consists of domain name 
        r=r+["domain name:"+dn+"\n"]#adding to final result
        #ranking
        url_for_rank="https://alexa.com/siteinfo/"+dn
        page=requests.get(url_for_rank)
        soup=BeautifulSoup(page.content,'html.parser')
        try:
            global_rank=str(soup.find('div', {"class": "rankmini-rank"}))
            rank=re.split('\n',global_rank)[1]
            rank=re.split('>',rank)[-1]
            
        except Exception:
            rank='10000000'
        ra=re.split(',',rank)
        rank=''
        for i in ra:
            rank=rank+i
        rank=int(rank)
        y[0].append(rank)#adding result to deciding attribute
        #having ip adress   
        count=0
        for i in dn:
            if i=='.':
                count=count+1
        if(count>=5):
            flag=1
        else:
           flag=0
        y[0].append(flag) 
        #isvalid
        if is_registered(domain):#THOMAS ELDHO 20BCT0113
            y[0].append(1)
        else:
            y[0].append(0)
        #age of domain
        activetime=0
        if is_registered(dn):
           data=whois.whois(dn)
           if type(data.creation_date)==list:
               creation_date=data.creation_date[0]
           
           else:
              creation_date=data.creation_date
           if creation_date ==None:
                activetime=1
           else: 
               activetime=(datetime.now()-creation_date).days
        y[0].append(activetime) 
        #url length
        y[0].append(len(url))
        #@check 
        flag=0
        for i in url:
            if i=='@':
                flag=1
                break 
        y[0].append(flag)
        # // present
        flag=0
        for i in dn:
            if i=='//':
                flag=1
                break 
        y[0].append(flag)
        #- have
        flag=0
        for i in dn:
            if i=='-':
                flag=1
                break 
        y[0].append(flag)
        #domainlen
        y[0].append(len(dn))
        #nu of sub domain
        count=0
        for i in dn:
            if i=='.':
                count=count+1
        y[0].append(count)
        
        
        #machine learning  
        df = pd.read_csv('dataset.csv')#reading dataset
        X = df.drop(columns=['domain','label'])#deciding attributes
        Y=df['label']#result
        X_train,X_test,Y_train,Y_test=train_test_split(X,Y,test_size=0.8,random_state=10)#splitting to training and test data
        r=r+["rank of the site is "+str(y[0][0])+"\n"]
        r=r+["is ip adress present in domain: "+str(bool(y[0][1]))+"\n"]
        r=r+["validity of the site: "+str(bool(y[0][2]))+"\n"]
        r=r+["age of the domain: "+str(y[0][3])+"\n"]
        r=r+["length of the url is "+str(y[0][4])+"\n"]
        r=r+["is @ present in url is "+str(bool(y[0][5]))+"\n"]
        r=r+["is the url redirected: "+str(bool(y[0][6]))+"\n"]
        r=r+["is hi-phen present : "+str(bool(y[0][7]))+"\n"]
        r=r+["length of the domain is "+str(y[0][8])+"\n"]
        r=r+["number of subdomains is "+str(y[0][9])+"\n"]
        lacc=0 #accuracy score for legitmate sites
        pacc=0 #accuracy score for phishing
        model=DecisionTreeClassifier()#accuracy and result for decisin tree classifier 
        model.fit(X,Y)
        y1_pred = model.predict(y)
        predictions = model.predict(X_test)
        acccuracy=100.0 *accuracy_score(Y_test,predictions)
        if y1_pred[0]==0:
            print('leg')
            lacc=lacc+acccuracy
            pacc=pacc+100-acccuracy
        else:
            print('Phish')
            lacc=lacc+100-acccuracy
            pacc=pacc+acccuracy
        model=RandomForestClassifier()#accuracy and result for randomn tree classifier
        model.fit(X,Y)
        y2_pred=model.predict(y)
        predictions = model.predict(X_test)
        acccuracy=100.0 *accuracy_score(Y_test,predictions)
        if y2_pred[0]==0:
             print('leg')
             lacc=lacc+acccuracy
             pacc=pacc+100-acccuracy
        else:
            print('phish')
            lacc=lacc+100-acccuracy
            pacc=pacc+acccuracy
        model=MultinomialNB(alpha=1.0)#accuracy and result for Naive Bayes.
        model.fit(X,Y)
        y3_pred=model.predict(y)
        predictions = model.predict(X_test)
        acccuracy=100.0 *accuracy_score(Y_test,predictions)
        if y3_pred[0]==0:
             print('leg')
             lacc=lacc+acccuracy
             pacc=pacc+100-acccuracy
        else:
            print('phish')
            lacc=lacc+100-acccuracy
            pacc=pacc+acccuracy
        if (lacc>pacc):#final result laccc for legitmate score and pacc phishing score
           final_result="The mentioned url "+url+" is likely to be legitmate\n"
           ac=str(lacc/3)
           flag=True
           n_row=[dn]+y[0]+[1]
        else:
            final_result="The mentioned url "+url+" is likely to be a scam\phishing site\n"
            ac=str(pacc/3)
            flag=False
            n_row=[dn]+y[0]+[0]
    else:#if the url doesnt exist
        r=["connection to the given url cannot be made. Please check if the provided url if the url site is permitted access by your network provider."]
        ac=''
        flg=False
        flag=""
        final_result=''
        if url.isspace():
            messages.info(request,"invalid input")
            return redirect('/')
        else:
            return render(request,"result.html",{"res":r,"final_result":final_result,"accuracy":ac,'flag':flag,'flg':flg})#sends r to result.html
    #THOMAS ELDHO 20BCT0113