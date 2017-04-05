#!/usr/bin/env python

import httplib
import sys
import argparse
import mimetools
import mimetypes
import os
import time
import urllib
import urllib2
import webbrowser
import json
from xml.dom.minidom import parse
import hashlib
import errno
import re

FLICKR = {
	"title"       : "flup",
	"description" : "The Command Line Flickr Uploader",
	"tags"        : "auto-upload",
	"is_public"   : "0",
	"is_friend"   : "0",
	"is_family"   : "0",
	"api_key"     : "9ce8a8a7b7eb0f3dc958238ef7bcacb5",
	"secret"      : "c8f4bbb4e8517210"
}

TOKEN_PATH     = os.path.join( os.path.dirname( sys.argv[0] ), ".flickrToken" )
IGNORED_REGEX  = [ re.compile( regex ) for regex in [] ]
ALLOWED_EXT    = [ "jpg", "png", "avi", "mov", "mpg", "mp4", "3gp" ]
FILE_MAX_SIZE  = 50000000
SOCKET_TIMEOUT = 60

if sys.version_info < ( 2, 7 ):
	sys.stderr.write( "This script requires Python 2.7 or newer.\n" )
	sys.stderr.write( "Current version: " + sys.version + "\n" )
	sys.stderr.flush()
	sys.exit( 1 )

class APIConstants:
	base    = "https://api.flickr.com/services/"
	rest    = base + "rest/"
	auth    = base + "auth/"
	upload  = base + "upload/"
	replace = base + "replace/"

	def __init__( self ):
		pass

api = APIConstants()

class FLUP:
	token = None
	perms = ""

	def __init__( self ):
		self.token = self.getCachedToken()

	def signAPICall( self, data ):
		keys = data.keys()
		keys.sort()
		sig = ""
		for a in keys:
			sig += ( a + data[a] )

		f = FLICKR["secret"] + "api_key" + FLICKR["api_key"] + sig

		return hashlib.md5( f ).hexdigest()

	def generateAPIRequest( self, base, data, sig ):
		data['api_key'] = FLICKR["api_key"]
		data['api_sig'] = sig
		encoded_url = base + "?" + urllib.urlencode( data )
		return encoded_url

	def authenticate( self ):
		print( "Getting new token" )
		self.getFrob()
		self.getAuthKey()
		self.getToken()
		self.cacheToken()

	def getFrob( self ):
		d = {
			"method": "flickr.auth.getFrob",
			"format": "json",
			"nojsoncallback": "1"
		}

		sig = self.signAPICall( d )
		url = self.generateAPIRequest( api.rest, d, sig )

		try:
			response = self.callAPI( url )
			if ( self.responseIsGood( response ) ):
				FLICKR["frob"] = str( response["frob"]["_content"] )
			else:
				self.reportError( response )

		except:
			print( "Error: cannot get frob:" + str( sys.exc_info() ) )

	def getAuthKey( self ):
		d = {
			"frob": FLICKR["frob"],
			"perms": "delete"
		}

		sig = self.signAPICall( d )
		url = self.generateAPIRequest( api.auth, d, sig )
		ans = ""

		try:
			webbrowser.open( url )
			print( "Copy-paste following URL into a web browser and follow instructions:" )
			print( url )
			ans = raw_input( "Have you authenticated this application? (Y/N): " )

		except:
			print( str( sys.exc_info() ) )
		
		if ( ans.lower() == "n" ):
			print( "You need to allow this program to access your Flickr site." )
			print( "Copy-paste following URL into a web browser and follow instructions:" )
			print( url )
			print( "After you have allowed access restart FLUP.py" )
			sys.exit()

	def getToken( self ):
		d = {
			"method": "flickr.auth.getToken",
			"frob": str( FLICKR["frob"] ),
			"format": "json",
			"nojsoncallback": "1"
		}

		sig = self.signAPICall( d )
		url = self.generateAPIRequest( api.rest, d, sig )

		try:
			res = self.callAPI( url )
			if ( self.responseIsGood( res ) ):
				self.token = str( res['auth']['token']['_content'] )
				self.perms = str( res['auth']['perms']['_content'] )
				self.cacheToken()
			else:
				self.reportError( res )
		except:
			print( str( sys.exc_info() ) )

	def getCachedToken( self ):
		if ( os.path.exists( TOKEN_PATH ) ):
			return open( TOKEN_PATH ).read()
		else:
			return None

	def cacheToken( self ):
		try:
			open( TOKEN_PATH, "w" ).write( str( self.token ) )
		except:
			print( "Issue writing token to local cache ", str( sys.exc_info() ) )

	def checkToken( self ):
		if ( self.token == None ):
			return False
		else:
			d = {
				"auth_token": str( self.token ),
				"method": "flickr.auth.checkToken",
				"format": "json",
				"nojsoncallback": "1"
			}

			sig = self.signAPICall( d )
			url = self.generateAPIRequest( api.rest, d, sig )

			try:
				res = self.callAPI( url )
				if ( self.responseIsGood( res ) ):
					self.token = res['auth']['token']['_content']
					self.perms = res['auth']['perms']['_content']
					return True
				else:
					self.reportError( res )

			except:
				print( str( sys.exc_info() ) )

			return False

	def build_request( self, theurl, fields, files, txheaders=None ):
		content_type, body = self.encode_multipart_formdata( fields, files )
		if not txheaders: txheaders = {}
		txheaders['Content-type'] = content_type
		txheaders['Content-length'] = str( len( body ) )

		return urllib2.Request( theurl, body, txheaders )

	def encode_multipart_formdata( self, fields, files, BOUNDARY='-----' + mimetools.choose_boundary() + '-----' ):
		CRLF = '\r\n'
		L = []
		
		if isinstance( fields, dict ):
			fields = fields.items()

		for ( key, value ) in fields:
			L.append( '--' + BOUNDARY )
			L.append( 'Content-Disposition: form-data; name="%s"' % key )
			L.append( '' )
			L.append( value )

		for ( key, filename, value ) in files:
			filetype = mimetypes.guess_type( filename )[0] or 'application/octet-stream'
			L.append( '--' + BOUNDARY )
			L.append( 'Content-Disposition: form-data; name="%s"; filename="%s"' % ( key, filename ) )
			L.append( 'Content-Type: %s' % filetype )
			L.append( '' )
			L.append( value )

		L.append( '--' + BOUNDARY + '--' )
		L.append( '' )

		body = CRLF.join( L )
		content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
		
		return content_type, body

	def responseIsGood( self, res ):
		if ( not res == "" and res['stat'] == "ok" ):
			return True
		else:
			return False

	def reportError( self, res ):
		try:
			print( "Error: " + str( res['code'] + " " + res['message'] ) )
		except:
			print( "Error: " + str( res ) )

	def callAPI( self, url ):
		res = None

		try:
			res = urllib2.urlopen( url, timeout=SOCKET_TIMEOUT ).read()
		except urllib2.HTTPError, e:
			print( e.code )
		except urllib2.URLError, e:
			print( e.args )

		return json.loads( res, encoding='utf-8' )

	def upload( self ):
		allMedia = []

		for dirpath, dirnames, filenames in os.walk( unicode( args.path ), followlinks=True ):
			for f in filenames:
				filePath = os.path.join( dirpath, f )
				
				if any( ignored.search( f ) for ignored in IGNORED_REGEX ):
					continue

				ext = os.path.splitext( os.path.basename( f ) )[1][1:].lower()

				if ext in ALLOWED_EXT:
					fileSize = os.path.getsize( dirpath + "/" + f )
					if ( fileSize < FILE_MAX_SIZE ):
						allMedia.append( os.path.normpath( dirpath + "/" + f ).replace( "'", "\'" ) )

		changedMedia = allMedia
		changedMedia_count = len( changedMedia )

		print( "Found " + str( changedMedia_count ) + " files to upload" )

		count = 0
		for i, file in enumerate( changedMedia ):
			file_id = self.uploadFile( file, count + 1, changedMedia_count )

			if ( count == 0 ):
				set_id = self.createAlbum( args.album, file_id )
			else:
				self.addFileToAlbum( set_id, file_id )

			count = count + 1;

		print( 'Processed ' + str( count ) + ' files' )

	def uploadFile( self, file, fileNum, totalNum ):
		if args.dryrun:
			print( "Not Uploading " + file + "..." )
			return True

		success = False
		last_modified = os.stat( file ).st_mtime
		head, setName = os.path.split( os.path.dirname( file ) )

		try:
			photo = ( 'photo', file.encode( 'utf-8' ), open( file, 'rb' ).read() )
			file_checksum = self.md5Checksum( file )

			d = {
				"auth_token":  str( self.token ),
				"perms":       str( self.perms ),
				"title":       str( FLICKR["title"] ),
				"description": str( FLICKR["description"] ),
				"is_public":   str( FLICKR["is_public"] ),
				"is_friend":   str( FLICKR["is_friend"] ),
				"is_family":   str( FLICKR["is_family"] )
			}

			sig = self.signAPICall( d )
			d["api_sig"] = sig
			d["api_key"] = FLICKR["api_key"]

			url = self.build_request( api.upload, d, ( photo, ) )
			
			try:
				res = parse( urllib2.urlopen( url, timeout=SOCKET_TIMEOUT ) )
				search_result = None

			except ( IOError, httplib.HTTPException ):
				print( str( sys.exc_info() ) )
				print( "Check is file already uploaded" )
				time.sleep( 5 )

				search_result = self.photos_search( file_checksum )
				if search_result["stat"] != "ok":
					raise IOError( search_result )

				if int( search_result["photos"]["total"] ) == 0:
					print( "Not found. Uploading." )

				if int( search_result["photos"]["total"] ) > 1:
					raise IOError( "More then one file with same checksum, collisions? " + search_result )

				if int( search_result["photos"]["total"] ) == 1:
					return success

			if not search_result and res.documentElement.attributes['stat'].value != "ok":
				print( "A problem occurred while attempting to upload the file: " + file )
				raise IOError( str( res.toxml() ) )

			if search_result:
				print( "File already exists on Flickr: " + file )
			else:
				print( "(" + str( fileNum ) + "/" + str( totalNum ) + ") Successfully uploaded the file: " + file )

			if search_result:
				file_id = int( search_result["photos"]["photo"][0]["id"] )
			else:
				file_id = int( str( res.getElementsByTagName( 'photoid')[0].firstChild.nodeValue ) )

		except:
			print( str( sys.exc_info() ) )

		return file_id

	def addFileToAlbum( self, setId, file ):
		if args.dryrun:
				return True

		try:
			d = {
				"auth_token":     str( self.token ),
				"perms":          str( self.perms ),
				"format":         "json",
				"nojsoncallback": "1",
				"method":         "flickr.photosets.addPhoto",
				"photoset_id":    str( setId ),
				"photo_id":       str( file )
			}

			sig = self.signAPICall( d )
			url = self.generateAPIRequest( api.rest, d, sig )
			res = self.callAPI( url )

			if ( self.responseIsGood( res ) ):
				print( 'Added file "' + str( file ) + '" to album "' + args.album + '"' )

			else:
				if ( res['code'] == 1 ):
					print( "Album not found. Creating a new album titled " + args.album )
					head, setName = args.album
					self.createAlbum( setName, file )
				else:
					self.reportError( res )

		except:
			print( str( sys.exc_info() ) )

	def createAlbum( self, setName, primaryPhotoId ):
		if args.dryrun:
			print( 'Not creating new album "' + setName.decode( 'utf-8' ) + '"' )
			return True

		existing = self.getAlbumIdByName( setName )
		
		if ( existing ):
			print( 'Album ' + setName.decode( 'utf-8' ) + ' already exists at id ' + existing );
			return existing

		print( 'Creating new album "' + setName.decode('utf-8') + '"' )

		try:
			d = {
				"auth_token":       str( self.token ),
				"perms":            str( self.perms ),
				"format":           "json",
				"nojsoncallback":   "1",
				"method":           "flickr.photosets.create",
				"primary_photo_id": str( primaryPhotoId ),
				"title":            setName
			}

			sig = self.signAPICall( d )
			url = self.generateAPIRequest( api.rest, d, sig )
			res = self.callAPI( url )

			if ( self.responseIsGood( res ) ):
				return res["photoset"]["id"]
			else:
				print( d )
				self.reportError( res )

		except:
			print( str( sys.exc_info() ) )

		return False

	def md5Checksum( self, filePath ):
		with open( filePath, 'rb' ) as fh:
			m = hashlib.md5()
			
			while True:
				data = fh.read( 8192 )
				if not data:
					break
				m.update( data )

			return m.hexdigest()

	def getAlbums( self ):
		if args.dryrun:
			return True

		try:
			d = {
				"auth_token":     str( self.token ),
				"perms":          str( self.perms ),
				"format":         "json",
				"nojsoncallback": "1",
				"method":         "flickr.photosets.getList"
			}

			url = self.generateAPIRequest( api.rest, d, self.signAPICall( d ) )
			res = self.callAPI( url )

			if ( self.responseIsGood( res ) ):
				for row in res['photosets']['photoset']:
					setId = row['id']
					setName = row['title']['_content']
					primaryPhotoId = row['primary']
					print( u"{0} {1} {2}".format( setId, setName, primaryPhotoId ) )
			else:
				print( d )
				self.reportError( res )

		except:
			print( str( sys.exc_info() ) )

	def getAlbumIdByName( self, albumName ):
		try:
			d = {
				"auth_token"     : str( self.token ),
				"perms"          : str( self.perms ),
				"format"         : "json",
				"nojsoncallback" : "1",
				"method"         : "flickr.photosets.getList"
			}

			url = self.generateAPIRequest( api.rest, d, self.signAPICall( d ) )
			res = self.callAPI( url )

			if ( self.responseIsGood( res ) ):
				for row in res['photosets']['photoset']:
					if albumName == row['title']['_content']:
						return row['id']

			return False

		except:
			print( str( sys.exc_info() ) )
			return False

	def photos_search( self, checksum ):
		data = {
			"auth_token":     str( self.token ),
			"perms":          str( self.perms ),
			"format":         "json",
			"nojsoncallback": "1",
			"method":         "flickr.photos.search",
			"user_id":        "me",
			"tags":           'checksum:{}'.format( checksum ),
		}

		url = self.generateAPIRequest( api.rest, data, self.signAPICall( data ) )
		return self.callAPI( url )

if __name__ == "__main__":
	parser = argparse.ArgumentParser( description='Upload files to Flickr.' )
	parser.add_argument( '-a', '--album', help='The album name' )
	parser.add_argument( '-p', '--public', help='Make the album public', action='store_true' )
	parser.add_argument( '-t', '--tags', help='Space separated tags for all photos', action='store' )
	parser.add_argument( '-d', '--dryrun', help='Do a dry run', action='store_true' )
	parser.add_argument( 'path', help='Folder path of uploads' )
	args = parser.parse_args() 

	if FLICKR["api_key"] == "" or FLICKR["secret"] == "":
		print( "Please enter an API key and secret in the script file (see README)." )
		sys.exit()

	if args.public:
		FLICKR["is_public"] = "1"
		FLICKR["is_friend"] = "1"
		FLICKR["is_family"] = "1"
		print( FLICKR )

	flickr = FLUP()

	if not flickr.checkToken():
		flickr.authenticate()

	flickr.upload()