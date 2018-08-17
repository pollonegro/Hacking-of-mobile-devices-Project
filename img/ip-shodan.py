#!/usr/bin/env python
import shodan
import re
import socket
import os
import requests
import sys
import urllib2
import dns.resolver
from bs4 import BeautifulSoup
import dns.resolver
import xlsxwriter
from time import sleep
import argparse

sockets     = {}                                                        #PARA PIP - PUERTOS - BUSCANDO IP

API_KEY     = 'v4YpsPUJ3wjDxEqywwu6aF5OZKWj8kik'                        #API GENERICA
#API_KEY    = "TrJLuBlD3vfXGPXYBF8CGYTXuweS6hat"                        #API luis
#API_KEY    = "RCnzhJzhIWkxj0jYPgmU5Vsy5sA6vSo8"                        #API pollo 

# -------------------- CLASE --------------------

class Shodan:
    def __init__(self,API_KEY):
        self.api =  shodan.Shodan(API_KEY)    

    def buscar(self,cadena):
        try:
            resultado = self.api.search(str(cadena))
            return resultado
        except Exception as e:
            print('Warning: {}'.format(e))
            resultado = []
            return resultado

        
    def obtener_info_host(self,IP):
        try:
                results = self.api.host(IP)
                return results
        except Exception as e:
                print('Warning: {}'.format(e))
                results = []
                return results     

os.system('clear')
print('------------------------------------------------------------------------')
print('Procesando el archivo ip.txt y guardando en resultados_shodan.xlsx')


API_KEY     = "TrJLuBlD3vfXGPXYBF8CGYTXuweS6hat"                
api         = shodan.Shodan(API_KEY)
sockets     = {}
contador    = 2

try:
    workbook = xlsxwriter.Workbook('resultados_shodan.xlsx')
    worksheet = workbook.add_worksheet()

    


    with open('ip-TEST.txt', 'r') as file:
        for line in file.readlines():   
            line_ip = line.split('\n')[0]
            sleep(1)
            try:
                ipv4 = socket.gethostbyname(line_ip)
            
            except Exception,e:
                print('IP not found for domain {}'.format(line_ip))
                continue
                                    
                                    # CONVIERTE HOSTS A IPs ----------
            try:
                results = api.host(ipv4)
            except Exception,e:
                print('Warning: {}'.format(e))
                continue
                sleep(1)

            buffer2     = [results['ip_str'] + '--' + str(results['ports'])]
            #sleep(1)
            results2    = api.search('net:')

            for service in results2['matches']:
                
                ip      = results['ip_str']
                port    = results['ports']

                if ip not in sockets.keys():
                    sockets[str(ip)] = [str(port)]
                else:
                    sockets[str(ip)] = str(port)
            

            hostname = 'N/A'
            if len(results['hostnames']) > 0:
                hostname = results['hostnames'][0]

            print('------------------------------------------------------------------------')
            print('Target:         {}, {}, {}'.format(results['ip_str'], hostname, results['org']))
            print('Localizacion:   {}, {}, {}, {}'.format(results.get('country_code3'),results.get('country_name'),results.get('city'),results.get('postal_code')))
            
            s = requests.Session()
            r = s.get('https://www.shodan.io/host/' + ipv4)
            r.status_code = ('Estado: ' + str(r.status_code))
            soup = BeautifulSoup(r.text, "html.parser")

            serviceDetails = iter(soup.findAll("div", attrs={"class": "service-details"}))
            serviceMains = soup.findAll("div", attrs={"class": "service-main"})

            for serviceMain in serviceMains:
                currentService = next(serviceDetails)
                try:
                    serviceInfo = serviceMain.find("pre").contents[0]
                    print("Puerto:         " + currentService.find("div", attrs={"class": "port"}).contents[0]) + "/" + currentService.find("div", attrs={"class": "protocol"}).contents[0] + ' ' + currentService.find("div", attrs={"class": "state"}).contents[0]
                except Exception,e:
                    print('Error recovering port {}'.format(e))
                    continue
                    sleep(1)

                powerHeader     = ''
                powerHeader     = (serviceInfo.encode('utf-8'))

                serverHE = "Server:"    # ----------------- DETECTANDO SERVER EN CABECERA ------------------
                try:
                    if serverHE in powerHeader: 
                        print('Server:         {}'.format(powerHeader.split(serverHE)[1].split("\r\n")[0]) + '\n')
                        #print('Info encontrada, no se imprime por optimizar..')
                    else:
                        print('Server:          N/A' + '\n')
                    
                except Exception,e:
                    print('Error parseando cabecera')   

            # ------------- LIMPIAR CARACTERES RAROS DE PUERTOS -------------

            puertosLimpios =  str(results['ports']).replace(", ", " - ")
            puertosLimpios2 =  puertosLimpios.replace("]", " ")
            puertosLimpios3 =  puertosLimpios2.replace("[", " ")

            print('Fecha rastreo:  {}'.format(results.get('last_update')[0:10]))
            cveLimpio =  str(results.get('vulns')).replace("', u'", " | ")
            cveLimpio2 =  cveLimpio.replace("[u'", " ")
            cveLimpio3 =  cveLimpio2.replace("']", " ")
            print('CVEs:           {}'.format(cveLimpio3) + '\n')


            # ---- TITULOS COLUMNAS ----
            worksheet.write('A1', 'IP')
            worksheet.write('B1', 'HOSTNAME')
            worksheet.write('C1', 'PUERTO')
            worksheet.write('D1', 'FECHA UPDATE')
            worksheet.write('E1', 'CVEs')


            # ---- COLUMNA IP ----
            contadorFila = ('A' + str(contador))
            #print(contadorFila, results['ip_str'])
            worksheet.write(contadorFila, results['ip_str'])
            
            # ---- COLUMNA HOSTNAME ----
            contadorFila = ('B' + str(contador))
            worksheet.write(contadorFila, hostname)

            # ---- COLUMNA PUERTO ----
            contadorFila = ('C' + str(contador))
            worksheet.write(contadorFila, puertosLimpios3)

            # ---- COLUMNA UPDATE ----
            contadorFila = ('D' + str(contador))
            worksheet.write(contadorFila, results.get('last_update')[0:10])

            # ---- COLUMNA CVEs ----
            contadorFila = ('E' + str(contador))
            vulnss = results.get('vulns')

            if not vulnss == None:
                #print(' '.join(map(str, vulnss)))
                vulnLista = (' '.join(map(str, vulnss)))
                #print(vulnLista)
                worksheet.write(contadorFila, vulnLista)

            contador += 1

            # ------------------------------------------
    print('------ Se ha generado archivo Excel con los resultados ------' + '\n')
    workbook.close()

except Exception as e:
    print 'Error: %s' % e
    sys.exit(1)

