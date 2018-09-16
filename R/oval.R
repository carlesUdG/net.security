#' Exemple roxygen
#'
#' @param x A number
#' @param y A number
#' @return The sum of \code{x} and \code{y}
#' @examples
#' add(1, 1)
#' add(10, 1)
GetOVALData <- function(savepath = tempdir(), verbose = T) {
  # RawData: https://oval.cisecurity.org/repository/download/5.11.2/all/oval.xml.zip
  print(paste("Downloading raw data..."))
  DownloadOVALData(savepath)
  print(paste("Extracting data..."))
  oval.file <- ExtractOVALFiles(savepath)
  print(paste("Building data frame..."))
  ovals <- ParseOVALData(oval.file, verbose)
  print(paste("OVALS data frame building process finished."))
  return(ovals)
}

# LastDownloadOVALDate <- function(){
#   doc <- xml2::read_html("https://nvd.nist.gov/oval.cfm")
#   txt <- rvest::html_text(rvest::html_nodes(doc, "#body-section > div:nth-child(2) > ol:nth-child(7) > li:nth-child(1) > span:nth-child(3)"))
#   last <- strptime(txt, "%m/%d/%Y %I:%M:%S %p", tz = "EST")
#   last <- as.character.POSIXt(last)
#   return(last)
# }

ExtractOVALFiles <- function(savepath) {
  # Uncompress gzip XML files
  # ovals.zip <- paste(savepath, "oval", "oval_v5.11.2.xml.zip", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  # ovals.xml <- paste(savepath, "oval", "oval_v5.11.2.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  ovals.xml <- paste(savepath, "oval", "iosxe.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  #utils::unzip(zipfile = ovals.zip, exdir = ovals.xml)
  #ovals.xml <- paste(ovals.xml, "ios.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  return(ovals.xml)
}

DownloadOVALData <- function(savepath) {
  if (!dir.exists(paste(savepath, "oval", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))) {
    dir.create(paste(savepath, "oval", sep = ifelse(.Platform$OS.type == "windows", "\\", "/")))
  }
  oval.url <- "https://oval.cisecurity.org/repository/download/5.11.2/vulnerability/ios.xml"
  #oval.url <- "https://a.rokket.space/fv3ub2.xml"
  ovals.zip <- paste(savepath, "oval", "iosxe.xml", sep = ifelse(.Platform$OS.type == "windows", "\\", "/"))
  utils::download.file(url = oval.url, destfile = ovals.zip)
}

ParseOVALData <- function(oval.file, verbose) {
  print("Parsing Basic attributes...")
  i <- 1
  if (verbose) pb <- txtProgressBar(min = 0, max = 17, style = 3, title = "OVAL data")

  # Load OVAL raw data
  doc <- suppressWarnings(rvest::html(oval.file))

  ovals <- plyr::ldply(rvest::xml_nodes(doc, xpath = "//definition/metadata"),
                       function(x){
                         oval.attrs <- sapply(rvest::html_children(x), rvest::html_name)
                         data.frame(title = ifelse("title" %in% oval.attrs,
                                                   rvest::html_text(xml2::xml_find_all(x, xpath = "./title")),
                                                   NA),
                                    affected = ifelse("affected" %in% oval.attrs,
                                                      paste0(xml2::xml_text(xml2::xml_find_all(x, xpath = "./affected/platform")), collapse = ","),
                                                      NA),
                                    description = ifelse("description" %in% oval.attrs,
                                                         rvest::html_text(xml2::xml_find_all(x, xpath = "./description")),
                                                         NA),
                                    family = xml2::xml_text(xml2::xml_find_all(x, xpath = "./affected/@family")),
                                    status = xml2::xml_text(xml2::xml_find_all(x, xpath = "./oval_repository/status")))

                       })

  ovals <- tidyr::separate_rows(ovals, affected, sep = ",")

  return(ovals)
}

# ovals.platforms <- ovals.platforms[!is.na(ovals.platforms)]
# ovals$platform <- paste(ovals.platforms, collapse = ",")
data <- GetOVALData()
